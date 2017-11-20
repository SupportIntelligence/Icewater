
rule m3e9_3163397749d275d2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3163397749d275d2"
     cluster="m3e9.3163397749d275d2"
     cluster_size="85"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['006b4a4f5af0533b7f5bcf8262856aa4','1c45302d777e738962913342ba3a98a2','a4ff389966100738c786ab64dd1113e2']"

   strings:
      $hex_string = { 443a5b59460e7b54c5186db9a2749dee2fcee572d0192d78e9c45de7e2c99ec0f5a1f16886f8b18bc25332f7c827bf0a405f02cd91339631cf51fc08be9c2af6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
