
rule m3e9_5b41e3899a430b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5b41e3899a430b16"
     cluster="m3e9.5b41e3899a430b16"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="floxif pioneer bvrqhu"
     md5_hashes="['3489428e1150b0ef867e7ec24b6f90af','679096a60f2dbae1a1d57a52c8b0f3f2','c353198851f463d16bb6774f500f3579']"

   strings:
      $hex_string = { f589ec3bed199eb7f6b52609dc8ed1c9be1e7bc0cdac0c38864944ee5be3c5d247967950cb042dd5ad116ca5e1000958bd775885784dcc2541a34ed88118312f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
