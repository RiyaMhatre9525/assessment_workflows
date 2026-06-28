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

    @staticmethod
    def insert_assessment_result_returning_id(
        db: Session,
        assessment_id: str,
        status: str,
        domain_name: str
    ) -> str:

        record_id = str(uuid.uuid4())
        sql = text("""
            INSERT INTO assessment_result (
                id,
                assessment_id,
                status,
                domain_name
            )
            VALUES (
                :id,
                :assessment_id,
                :status,
                :domain_name
            )
        """)

        db.execute(
            sql,
            {
                "id": record_id,
                "assessment_id": assessment_id,
                "status": status,
                "domain_name": domain_name
            }
        )

        db.commit()
        return record_id

    @staticmethod
    def update_assessment_result(
        db: Session,
        result_id: str,
        status: str,
        domain_score: float,
        reasoning: str,
        improvement_recommendations: list | dict,
        additional_info: dict | None = None
    ) -> None:

        sql = text("""
            UPDATE assessment_result
            SET
                status = :status,
                domain_score = :domain_score,
                reasoning = :reasoning,
                improvement_recommendations = CAST(:improvement_recommendations AS JSONB),
                additional_info = CAST(:additional_info AS JSONB)
            WHERE id = :id
        """)

        db.execute(
            sql,
            {
                "id": result_id,
                "status": status,
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

