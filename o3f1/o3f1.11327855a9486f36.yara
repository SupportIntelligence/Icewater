
rule o3f1_11327855a9486f36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f1.11327855a9486f36"
     cluster="o3f1.11327855a9486f36"
     cluster_size="312"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakeapp riskware androidos"
     md5_hashes="['01756dcb9239951b14ae8a1347e43125','0202dfd0a342e99d63cdc148c6eb8c25','10d9e0a45b1a3bd25ffbb2bb02e5c071']"

   strings:
      $hex_string = { 8e2fa3c1f9e534874e48793330461bdec55232a16cfd777311d04d4bb32baf1a55dfb9e825ed22051c0d54476a5f18a74372667abff6ad76b7a950714a1291ab }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
