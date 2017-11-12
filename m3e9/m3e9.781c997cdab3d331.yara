
rule m3e9_781c997cdab3d331
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.781c997cdab3d331"
     cluster="m3e9.781c997cdab3d331"
     cluster_size="75"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbkrypt chinky"
     md5_hashes="['03fad16e17ef1af97e06cf53dd0da7d2','0a760c3f8d721add508f288a2e9cfa20','a4981940a2425cf4a9b70dfeac4f5c4b']"

   strings:
      $hex_string = { 578965f4c745f8703740008b75088bc683e0018945fc83e6fe568975088b06ff50048b0633ff66833d70c34200ff897dd4897dc4897dc0897dbc897db8897db4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
