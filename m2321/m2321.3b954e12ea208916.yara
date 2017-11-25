
rule m2321_3b954e12ea208916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3b954e12ea208916"
     cluster="m2321.3b954e12ea208916"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma emotet"
     md5_hashes="['1ae044dcc5e84141034bf090d6fa81af','9c8b5869dfb2034bb40ba351dfd5de3e','e7b396663ba11a42e6e28c6304161a6c']"

   strings:
      $hex_string = { 269b5a70c07948ef72d267314b9922164283dee93d7121a75c7a39f664fbbe3cb6683f35b8a4736f6cb3b44fbbfdf33bc29e6d1b3a782a5e867ef1ae3eb9e8dd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
