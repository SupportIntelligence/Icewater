
rule o3f1_11b27844a9486f36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f1.11b27844a9486f36"
     cluster="o3f1.11b27844a9486f36"
     cluster_size="167"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="riskware fakeapp androidos"
     md5_hashes="['09d969def9900a03a07ca3a4cd2d8e5b','0d196d5b1bffd7e56516c64704974790','20e2c7fce306d7857171b47421fe8537']"

   strings:
      $hex_string = { 8e2fa3c1f9e534874e48793330461bdec55232a16cfd777311d04d4bb32baf1a55dfb9e825ed22051c0d54476a5f18a74372667abff6ad76b7a950714a1291ab }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
