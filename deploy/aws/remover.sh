#!/bin/bash
# Remove tudo que o provisionar.sh criou (rode no CloudShell depois da apresentação).
set -uo pipefail
export AWS_REGION="${AWS_REGION:-sa-east-1}" AWS_PAGER=""
NOME=sorridonto
IDS=$(aws ec2 describe-instances --filters Name=tag:Name,Values=$NOME Name=instance-state-name,Values=pending,running,stopped,stopping --query 'Reservations[].Instances[].InstanceId' --output text)
[ -n "$IDS" ] && { aws ec2 terminate-instances --instance-ids $IDS >/dev/null; aws ec2 wait instance-terminated --instance-ids $IDS; echo "instância removida"; }
for A in $(aws ec2 describe-addresses --query 'Addresses[].AllocationId' --output text); do aws ec2 release-address --allocation-id "$A" && echo "IP elástico liberado"; done
SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=$NOME --query 'SecurityGroups[0].GroupId' --output text)
[ "$SG" != "None" ] && aws ec2 delete-security-group --group-id "$SG" && echo "security group removido"
aws iam remove-role-from-instance-profile --instance-profile-name $NOME-ec2 --role-name $NOME-ec2 2>/dev/null
aws iam delete-instance-profile --instance-profile-name $NOME-ec2 2>/dev/null
aws iam detach-role-policy --role-name $NOME-ec2 --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore 2>/dev/null
aws iam delete-role --role-name $NOME-ec2 2>/dev/null && echo "papel IAM removido"
echo "Concluído. (Libere também a visibilidade do repositório no GitHub, se quiser voltar a privado.)"
