
rule m3e9_5b5c6b899a430b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5b5c6b899a430b16"
     cluster="m3e9.5b5c6b899a430b16"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="floxif pioneer bvrqhu"
     md5_hashes="['2dd2969ea762f47fe70e659949262b7b','4d23713a13f61538b807fbe580c7d433','d3c2e7c9a58d202fd7a0d58e4ec71b0b']"

   strings:
      $hex_string = { f589ec3bed199eb7f6b52609dc8ed1c9be1e7bc0cdac0c38864944ee5be3c5d247967950cb042dd5ad116ca5e1000958bd775885784dcc2541a34ed88118312f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
