
rule j2321_34c6a5629935d595
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.34c6a5629935d595"
     cluster="j2321.34c6a5629935d595"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd androm backdoor"
     md5_hashes="['1be634aca1e7cc6c8e3bccf2295e2b3a','24d0f958b5cb7d6f7391f55826b165c4','d6b6181fb7b935d39fb48ffdd27c77e5']"

   strings:
      $hex_string = { e8193dee948a4ec4d2e94b3aa62f9dbff1170f03d1e0bbe5e57795af057afcad7cf6ddc15f7d35f8259f675f74d0a1c8de4ab9b0e74737dc0ce306f96d7372fe }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
