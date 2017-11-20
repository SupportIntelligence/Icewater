
rule m2377_4b1f6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.4b1f6a48c0000b12"
     cluster="m2377.4b1f6a48c0000b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit script html"
     md5_hashes="['49281c2093fee49f92872c70b0dbadd6','586f8f89be257a30d7445e24347ce8d7','efc78b933fb2537ad00a8d70827f09ee']"

   strings:
      $hex_string = { b8137a2c711ac165634b2ea09eaebaa4e6e06151637229759b742d92e733dfa15af8ddd5be54ef8d149a9634fad428f24297bb19f6f469e540490bcf6e2a870e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
