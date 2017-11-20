
rule j2321_11b9300600001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.11b9300600001912"
     cluster="j2321.11b9300600001912"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cosmicduke razy"
     md5_hashes="['286b2ee9303d3e31cce54f02f10bc2ce','4048fa36d3aa66cb3ee991d211738002','e20d1316d93bef774d69b529d552a0d1']"

   strings:
      $hex_string = { f75766cfdaa1ebb34f457c2b6c8f8bd986986d7576f5a9b475c7ecb763031faa9ecbefc6a6fceebeb9a3f6e6c08a4ab6ee81285895374d671eddf9e5875f6ec9 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
