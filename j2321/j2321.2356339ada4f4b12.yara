
rule j2321_2356339ada4f4b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.2356339ada4f4b12"
     cluster="j2321.2356339ada4f4b12"
     cluster_size="3"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre bublik generickd"
     md5_hashes="['5586c90415562804d48c41e95ce709b5','931d6310bd68bb87c2c468fb5be2ef47','c277b32ee64a6a268b6b3c7be4fac137']"

   strings:
      $hex_string = { 46067a3e50ca280fb9a2a04f6cbd8911531e2dfdf773c3191bb469d11d82a463e4a8d381920db94a70aac1978e777f6b3fb11b38f204792c23326a9b80c4b7e3 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
