
rule j3f7_611bea48c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f7.611bea48c4000932"
     cluster="j3f7.611bea48c4000932"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html iframeref"
     md5_hashes="['3d55a8f4b3811df3b0654f1e7ef38b6c','a0326bdff2bb88af9f174556e78a0fe1','b04578d677637b5e31d227d9778bc97f']"

   strings:
      $hex_string = { 3435207372633d687474703a2f2f6e6d736261736562616c6c2e636f6d2f706f73742e7068703f69643d3636363038383e3c2f696672616d653e3c2f626f6479 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
