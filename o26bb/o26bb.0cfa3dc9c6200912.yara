
rule o26bb_0cfa3dc9c6200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.0cfa3dc9c6200912"
     cluster="o26bb.0cfa3dc9c6200912"
     cluster_size="45"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kuzitui kuaizip kzip"
     md5_hashes="['376e3409e26b9e7669a5a39545aa5dfb115cad91','2ee27afad7c286934e4511952d06c0b88fbdea20','c4819ffb3d7f252204185b5efa35ad70d8ec969c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.0cfa3dc9c6200912"

   strings:
      $hex_string = { 785549404475694c6962404051414558484850415574616752454354404050425f57405a003f4f6e4d6f757365486f7665724057696e646f77496d706c426173 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
