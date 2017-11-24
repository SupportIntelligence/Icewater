
rule n3e9_4998254bc6620b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4998254bc6620b16"
     cluster="n3e9.4998254bc6620b16"
     cluster_size="19"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy malicious ayzg"
     md5_hashes="['1014435058c0a7fb2bef5c0d353e4e63','11e3372a4f32716a63282a727b071dc8','e4ce866a6daace767706cc3328eadcab']"

   strings:
      $hex_string = { 21bec26309c0a7e9448372320190ebba6900e196a9207f0e5051ae6525054148d59db3b460913f93581c570be49ae5ee8a5079a31ff949427df5941615fb35d1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
