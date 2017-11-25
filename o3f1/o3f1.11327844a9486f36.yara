
rule o3f1_11327844a9486f36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f1.11327844a9486f36"
     cluster="o3f1.11327844a9486f36"
     cluster_size="53"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="riskware fakeapp androidos"
     md5_hashes="['040247a69e6539ff7613e19e60ecc12c','0468eddbb5b6952b25ef69d92118e29a','41f28e1dcddbfab40a7e1f74369f45c8']"

   strings:
      $hex_string = { 8e2fa3c1f9e534874e48793330461bdec55232a16cfd777311d04d4bb32baf1a55dfb9e825ed22051c0d54476a5f18a74372667abff6ad76b7a950714a1291ab }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
