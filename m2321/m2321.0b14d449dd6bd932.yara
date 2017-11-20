
rule m2321_0b14d449dd6bd932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b14d449dd6bd932"
     cluster="m2321.0b14d449dd6bd932"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis hafen mikey"
     md5_hashes="['45a01ec2147ca28e284b1c54a2914b0c','4fee673856ab036326d3184845b26c3d','fb5b0aa521950d569a0bc35ef2f877e1']"

   strings:
      $hex_string = { d8cc566b22acf6a299879fe75e01ae4b162148e9451803bf85442915e46cd19cfcf9725b7428f1fd70b5619d96c38f6937b63ee51ea353306f11ff89b38ca4ab }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
