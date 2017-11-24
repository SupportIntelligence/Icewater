
rule m2321_111c9cb9c9800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.111c9cb9c9800b12"
     cluster="m2321.111c9cb9c9800b12"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy shifu cfca"
     md5_hashes="['140501792c8b99687daede1de659b395','197443d436d20dd3e401f26df971dbaa','d9e9a14e9721633cd6c205078591018f']"

   strings:
      $hex_string = { 69fd4d6d399643ab04f3442a363b6bf7e51ba39c510fb2257513b8db5889b16e2ed47e981c8162e523ee37e225d5ae50248e7341add9bfa01ad2dd0eb34099b5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
