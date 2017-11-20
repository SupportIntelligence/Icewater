
rule j2321_11b9100600001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.11b9100600001912"
     cluster="j2321.11b9100600001912"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cosmicduke razy"
     md5_hashes="['1b4f1609fd1b4b0f9b2b65c0c6a3c029','3c142798c8239d74a4315d50c6826501','f31f6d50cbf88ff756e3cb1aea74e211']"

   strings:
      $hex_string = { f75766cfdaa1ebb34f457c2b6c8f8bd986986d7576f5a9b475c7ecb763031faa9ecbefc6a6fceebeb9a3f6e6c08a4ab6ee81285895374d671eddf9e5875f6ec9 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
