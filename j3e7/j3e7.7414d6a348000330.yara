
rule j3e7_7414d6a348000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7414d6a348000330"
     cluster="j3e7.7414d6a348000330"
     cluster_size="40"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['0c6ce81284f1b7fe9200d96e1e61da24','155125900196a62fd8100aac34d720fa','65a195038294cc85c9e1418d143889cd']"

   strings:
      $hex_string = { 672f436c6173733b00135b4c6a6176612f6c616e672f4f626a6563743b000161001a616e64726f69642e6170702e41637469766974795468726561640026616e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
