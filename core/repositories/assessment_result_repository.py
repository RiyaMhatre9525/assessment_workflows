import json
import uuid
from sqlalchemy import text
from sqlalchemy.orm import Session


class AssessmentResultRepository:

    @staticmethod
    def insert_assessment_result(
        db: Session,
        assessment_id: str,
        status: str,
        domain_name: str,
        domain_score: float,
        reasoning: str,
        improvement_recommendations: list | dict,
        additional_info: dict | None = None
    ):

        sql = text("""
            INSERT INTO assessment_result (
                id,
                assessment_id,
                status,
                domain_name,
                domain_score,
                reasoning,
                improvement_recommendations,
                additional_info
            )
            VALUES (
                :id,
                :assessment_id,
                :status,
                :domain_name,
                :domain_score,
                :reasoning,
                CAST(:improvement_recommendations AS JSONB),
                CAST(:additional_info AS JSONB)
            )
        """)

        db.execute(
            sql,
            {
                "id": str(uuid.uuid4()),
                "assessment_id": assessment_id,
                "status": status,
                "domain_name": domain_name,
                "domain_score": domain_score,
                "reasoning": reasoning,
                "improvement_recommendations": json.dumps(
                    improvement_recommendations
                ),
                "additional_info": json.dumps(
                    additional_info or {}
                )
            }
        )

        db.commit()