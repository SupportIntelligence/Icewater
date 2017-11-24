
rule n2321_399a1599c6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.399a1599c6620b32"
     cluster="n2321.399a1599c6620b32"
     cluster_size="153"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="amonetize genericrxdd applicunwnt"
     md5_hashes="['045783a1d2ff68da54679b18dc80ef0e','05e02d2c358fe5005790e61fa97af883','1ac6c303af1d87d76ad945f4ac1224e5']"

   strings:
      $hex_string = { 67121a6354276913ded8240d43c34dc6e7f85aa6e59472037df47690ed978ca8c5643a0f792d1cda90af311b7be27fd36eb1be09153462f7fccab76f2f840151 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
