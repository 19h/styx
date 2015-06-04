/// <reference path="../estree.ts"/>
/// <reference path="../flow.ts"/>
/// <reference path="../util/idGenerator.ts"/>
/// <reference path="../collections/stack.ts"/>
/// <reference path="enclosingIterationStatement.ts"/>
/// <reference path="expressions/negator.ts"/>
/// <reference path="expressions/stringifier.ts"/>

module Styx {
    export class Parser {
        public controlFlowGraph: ControlFlowGraph;
        
        private idGenerator: Util.IdGenerator;
        private enclosingIterationStatements: Collections.Stack<EnclosingIterationStatement>;
        
        constructor(private program: ESTree.Program) {
            this.idGenerator = Util.createIdGenerator();
            this.enclosingIterationStatements = new Collections.Stack<EnclosingIterationStatement>();
            
            this.controlFlowGraph = this.parseProgram(program);
        }
    
        private parseProgram(program: ESTree.Program): ControlFlowGraph {
            let entryNode = this.createNode();
            let flowGraph = new ControlFlowGraph(entryNode);
    
            this.parseStatements(program.body, flowGraph.entry);
    
            return flowGraph;
        }
    
        private parseStatements(statements: ESTree.Statement[], currentNode: FlowNode): FlowNode {
            for (let statement of statements) {
                currentNode = this.parseStatement(statement, currentNode);
                
                if (Parser.isAbruptCompletion(statement)) {
                    // If we encounter an abrupt completion, normal control flow is interrupted
                    // and the following statements aren't executed
                    return currentNode;
                }
            }
            
            return currentNode;
        }
    
        private parseStatement(statement: ESTree.Statement, currentNode: FlowNode): FlowNode {
            if (statement === null || statement.type === ESTree.NodeType.DebuggerStatement) {
                return currentNode;
            }
            
            if (statement.type === ESTree.NodeType.EmptyStatement) {
                return this.parseEmptyStatement(<ESTree.EmptyStatement>statement, currentNode);
            }
            
            if (statement.type === ESTree.NodeType.BlockStatement) {
                return this.parseBlockStatement(<ESTree.BlockStatement>statement, currentNode);
            }
            
            if (statement.type === ESTree.NodeType.VariableDeclaration) {
                return this.parseVariableDeclaration(<ESTree.VariableDeclaration>statement, currentNode);
            }
            
            if (statement.type === ESTree.NodeType.IfStatement) {
                return this.parseIfStatement(<ESTree.IfStatement>statement, currentNode);
            }
            
            if (statement.type === ESTree.NodeType.BreakStatement) {
                return this.parseBreakStatement(<ESTree.BreakStatement>statement, currentNode);
            }
            
            if (statement.type === ESTree.NodeType.ContinueStatement) {
                return this.parseContinueStatement(<ESTree.ContinueStatement>statement, currentNode);
            }
            
            if (statement.type === ESTree.NodeType.WhileStatement) {
                return this.parseWhileStatement(<ESTree.WhileStatement>statement, currentNode);
            }
            
            if (statement.type === ESTree.NodeType.DoWhileStatement) {
                return this.parseDoWhileStatement(<ESTree.DoWhileStatement>statement, currentNode);
            }
            
            if (statement.type === ESTree.NodeType.ForStatement) {
                return this.parseForStatement(<ESTree.ForStatement>statement, currentNode);
            }
            
            if (statement.type === ESTree.NodeType.ExpressionStatement) {
                return this.parseExpressionStatement(<ESTree.ExpressionStatement>statement, currentNode);
            }
            
            throw Error(`Encountered unsupported statement type '${statement.type}'`);
        }
        
        private parseEmptyStatement(emptyStatement: ESTree.EmptyStatement, currentNode: FlowNode): FlowNode {
            return this.createNode().appendTo(currentNode, "(empty)", EdgeType.Epsilon);
        }
        
        private parseBlockStatement(blockStatement: ESTree.BlockStatement, currentNode: FlowNode): FlowNode {
            return this.parseStatements(blockStatement.body, currentNode);
        }
    
        private parseVariableDeclaration(declaration: ESTree.VariableDeclaration, currentNode: FlowNode): FlowNode {
            for (let declarator of declaration.declarations) {
                let initString = Expressions.Stringifier.stringify(declarator.init);
                let edgeLabel = `${declarator.id.name} = ${initString}`;
                currentNode = this.createNode().appendTo(currentNode, edgeLabel);
            }
    
            return currentNode;
        }
    
        private parseIfStatement(ifStatement: ESTree.IfStatement, currentNode: FlowNode): FlowNode {
            return ifStatement.alternate === null
                ? this.parseSimpleIfStatement(ifStatement, currentNode)
                : this.parseIfElseStatement(ifStatement, currentNode);
        }
    
        private parseSimpleIfStatement(ifStatement: ESTree.IfStatement, currentNode: FlowNode): FlowNode {
            let truthyCondition = ifStatement.test;
            let truthyConditionLabel = Expressions.Stringifier.stringify(truthyCondition);
            
            let falsyCondition = Expressions.Negator.negateTruthiness(truthyCondition);
            let falsyConditionLabel = Expressions.Stringifier.stringify(falsyCondition);
            
            let thenNode = this.createNode()
                .appendTo(currentNode, truthyConditionLabel, EdgeType.Conditional);
            
            let endOfThenBranch = this.parseStatement(ifStatement.consequent, thenNode);
            
            let finalNode = this.createNode()
                .appendTo(currentNode, falsyConditionLabel, EdgeType.Conditional);
            
            if (endOfThenBranch) {
                finalNode.appendEpsilonEdgeTo(endOfThenBranch);
            }
            
            return finalNode;
        }
    
        private parseIfElseStatement(ifStatement: ESTree.IfStatement, currentNode: FlowNode): FlowNode {
            // Then branch
            let thenCondition = ifStatement.test;
            let thenLabel = Expressions.Stringifier.stringify(thenCondition);
            let thenNode = this.createNode().appendTo(currentNode, thenLabel, EdgeType.Conditional);
            let endOfThenBranch = this.parseStatement(ifStatement.consequent, thenNode);
            
            // Else branch
            let elseCondition = Expressions.Negator.negateTruthiness(thenCondition);
            let elseLabel = Expressions.Stringifier.stringify(elseCondition); 
            let elseNode = this.createNode().appendTo(currentNode, elseLabel, EdgeType.Conditional);
            let endOfElseBranch = this.parseStatement(ifStatement.alternate, elseNode);
            
            let finalNode = this.createNode();
            
            if (endOfThenBranch) {
                finalNode.appendEpsilonEdgeTo(endOfThenBranch);
            }
            
            if (endOfElseBranch) {
                finalNode.appendEpsilonEdgeTo(endOfElseBranch);
            }
            
            return finalNode;
        }
        
        private parseBreakStatement(breakStatement: ESTree.BreakStatement, currentNode: FlowNode): FlowNode {
            let enclosingLoop = this.enclosingIterationStatements.peek();
            enclosingLoop.breakTarget.appendTo(currentNode, "break", EdgeType.AbruptCompletion);
            
            return null;
        }
        
        private parseContinueStatement(continueStatement: ESTree.ContinueStatement, currentNode: FlowNode): FlowNode {
            let enclosingLoop = this.enclosingIterationStatements.peek();
            enclosingLoop.continueTarget.appendTo(currentNode, "continue", EdgeType.AbruptCompletion);
            
            return null;
        }
        
        private parseWhileStatement(whileStatement: ESTree.WhileStatement, currentNode: FlowNode): FlowNode {
            // Truthy test (enter loop)
            let truthyCondition = whileStatement.test;
            let truthyConditionLabel = Expressions.Stringifier.stringify(truthyCondition);
            
            // Falsy test (exit loop)
            let falsyCondition = Expressions.Negator.negateTruthiness(truthyCondition);            
            let falsyConditionLabel = Expressions.Stringifier.stringify(falsyCondition);
            
            let loopBodyNode = this.createNode().appendTo(currentNode, truthyConditionLabel, EdgeType.Conditional);
            let finalNode = this.createNode();
            
            this.enclosingIterationStatements.push({
                iterationStatement: whileStatement,
                continueTarget: currentNode,
                breakTarget: finalNode
            });
            
            let endOfLoopBodyNode = this.parseStatement(whileStatement.body, loopBodyNode);
            
            if (endOfLoopBodyNode) {
                currentNode.appendEpsilonEdgeTo(endOfLoopBodyNode);
            }
            
            this.enclosingIterationStatements.pop();
            
            return finalNode
                .appendTo(currentNode, falsyConditionLabel, EdgeType.Conditional);
        }
        
        private parseDoWhileStatement(doWhileStatement: ESTree.DoWhileStatement, currentNode: FlowNode): FlowNode {
            // Truthy test (enter loop)
            let truthyCondition = doWhileStatement.test;
            let truthyConditionLabel = Expressions.Stringifier.stringify(truthyCondition);
            
            // Falsy test (exit loop)
            let falsyCondition = Expressions.Negator.negateTruthiness(truthyCondition);            
            let falsyConditionLabel = Expressions.Stringifier.stringify(falsyCondition);
            
            let testNode = this.createNode();
            let finalNode = this.createNode();
            
            this.enclosingIterationStatements.push({
                iterationStatement: doWhileStatement,
                continueTarget: testNode,
                breakTarget: finalNode
            });
            
            let endOfLoopBodyNode = this.parseStatement(doWhileStatement.body, currentNode);
            
            this.enclosingIterationStatements.pop();
            
            currentNode.appendTo(testNode, truthyConditionLabel, EdgeType.Conditional);
            finalNode.appendTo(testNode, falsyConditionLabel, EdgeType.Conditional);
            
            if (endOfLoopBodyNode) {
                testNode.appendEpsilonEdgeTo(endOfLoopBodyNode);
            }
            
            return finalNode;
        }
        
        private parseForStatement(forStatement: ESTree.ForStatement, currentNode: FlowNode): FlowNode {
            // Parse initialization
            let testDecisionNode = this.parseStatement(forStatement.init, currentNode);
            
            // Create nodes for loop cornerstones
            let beginOfLoopBodyNode = this.createNode();
            let updateNode = this.createNode();
            let finalNode = this.createNode();
            
            if (forStatement.test) {
                // If the loop has a test expression,
                // we need to add truthy and falsy edges
                let truthyCondition = forStatement.test;
                let falsyCondition = Expressions.Negator.negateTruthiness(truthyCondition);
                
                // Create edges labels
                let truthyConditionLabel = Expressions.Stringifier.stringify(truthyCondition);                
                let falsyConditionLabel = Expressions.Stringifier.stringify(falsyCondition);
                
                // Add truthy and falsy edges
                beginOfLoopBodyNode.appendTo(testDecisionNode, truthyConditionLabel, EdgeType.Conditional)
                finalNode.appendTo(testDecisionNode, falsyConditionLabel, EdgeType.Conditional);
            } else {
                // If the loop doesn't have a test expression,
                // the loop body starts unconditionally after the initialization
                beginOfLoopBodyNode.appendEpsilonEdgeTo(testDecisionNode);
            }
            
            // Begin loop context
            this.enclosingIterationStatements.push({
                iterationStatement: forStatement,
                continueTarget: updateNode,
                breakTarget: finalNode
            });
            
            // Parse body
            let endOfLoopBodyNode = this.parseStatement(forStatement.body, beginOfLoopBodyNode);
            
            // End loop context
            this.enclosingIterationStatements.pop();
            
            if (forStatement.update) {
                // If the loop has an update expression,
                // parse it and append it to the end of the loop body
                let endOfUpdateNode = this.parseExpression(forStatement.update, updateNode);
                testDecisionNode.appendEpsilonEdgeTo(endOfUpdateNode);                                   
            } else {
                // If the loop doesn't have an update expression,
                // treat the update node as a dummy and point it to the test node
                testDecisionNode.appendEpsilonEdgeTo(updateNode);
            }
            
            if (endOfLoopBodyNode) {
                // If we reached the end of the loop body through normal control flow,
                // continue regularly with the update
                updateNode.appendEpsilonEdgeTo(endOfLoopBodyNode);
            }
            
            return finalNode;
        }
        
        private parseExpressionStatement(expressionStatement: ESTree.ExpressionStatement, currentNode: FlowNode): FlowNode {
            return this.parseExpression(expressionStatement.expression, currentNode);
        }
        
        private parseExpression(expression: ESTree.Expression, currentNode: FlowNode): FlowNode {
            if (expression.type === ESTree.NodeType.SequenceExpression) {
                return this.parseSequenceExpression(<ESTree.SequenceExpression>expression, currentNode);
            }
            
            let expressionLabel = Expressions.Stringifier.stringify(expression);
            
            return this.createNode()
                .appendTo(currentNode, expressionLabel);
        }
        
        private parseSequenceExpression(sequenceExpression: ESTree.SequenceExpression, currentNode: FlowNode): FlowNode {
            for (let expression of sequenceExpression.expressions) {
                currentNode = this.parseExpression(expression, currentNode);
            }
            
            return currentNode;
        }
        
        private static isAbruptCompletion(statement: ESTree.Statement): boolean {
            switch (statement.type) {
                case ESTree.NodeType.BreakStatement:
                case ESTree.NodeType.ContinueStatement:
                    return true;
                    
                default:
                    return false;
            }
        }
        
        private createNode(): FlowNode {
            return new FlowNode(this.idGenerator.makeNew());
        }
    }
}
