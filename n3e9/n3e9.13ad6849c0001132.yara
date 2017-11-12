
rule n3e9_13ad6849c0001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13ad6849c0001132"
     cluster="n3e9.13ad6849c0001132"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mikey banbra banker"
     md5_hashes="['1fc53a74f3c139a2dcd42e7c943ab61a','86c5dde2b4390a5617f58d993c04cb37','efe6e770646f1d4060149297ad61d6b7']"

   strings:
      $hex_string = { 5233320000444953504c415900636f6d6d6374726c5f447261674c6973744d73670000000018284200daa24100533c410040114000eb2e410097484100fa2f41 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
