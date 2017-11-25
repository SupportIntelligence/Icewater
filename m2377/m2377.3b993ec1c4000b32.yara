
rule m2377_3b993ec1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.3b993ec1c4000b32"
     cluster="m2377.3b993ec1c4000b32"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['38bdfd940cbb4113c76b8326dc2f4022','8cbef6c309c46655c60c120e88651d76','e385824265ea4848530bb4bc8fafd6b7']"

   strings:
      $hex_string = { 7843734b636c79302f5534655145362d657039492f414141414141414153694d2f574532704a39576b6a4e4d2f7337322d632f312e6a7067272077696474683d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
