
rule k2321_19159fa9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.19159fa9ca000b12"
     cluster="k2321.19159fa9ca000b12"
     cluster_size="96"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['0aa43a90a7b36b220417ea3ca00a55f4','0b6712dabeb4d42872f6846b4d220b5c','3eca35a0113f12f763c33ef5c4cdf20e']"

   strings:
      $hex_string = { 5ad9a8294361ed987068f769715e671136138f83339792073e2531f29a1db07d12a8322a76b887c26489aa5c0d2ee76b0927d7ad78a6ffd4246d21c97ed0a9f5 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
