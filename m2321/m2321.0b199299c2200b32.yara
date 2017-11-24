
rule m2321_0b199299c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b199299c2200b32"
     cluster="m2321.0b199299c2200b32"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut midie shodi"
     md5_hashes="['19f58ade388dba62305f4b196791a6f9','52336f162926b3f0713374f777933944','bf184d6ab1bee98ddb03338b3965db5c']"

   strings:
      $hex_string = { 61f6a59da063f8a7adf895c9270491f20ee8afb1d9cad3ccf70dc6ac40fb57b33e226c3119c476ed30a1d228aadc481d2c13a98a5442b0e200d7bf59db21d12a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
