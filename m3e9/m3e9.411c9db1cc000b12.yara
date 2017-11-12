
rule m3e9_411c9db1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411c9db1cc000b12"
     cluster="m3e9.411c9db1cc000b12"
     cluster_size="114"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['0ec8f12738d3374e579f7d1d7bcda6c0','169a7c56ca9faf9a2910f1c4c4932a19','8d5926cf3d7e94496667da272322f296']"

   strings:
      $hex_string = { 55e83661f3a98b57130d417894ddaaa51c634c5055762be70176187949aca05480afcdc51a4938702b2af520b259e1d16888ef56324be5b512455549e33eb706 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
