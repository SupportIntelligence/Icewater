
rule m2321_0b298c1495a26b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b298c1495a26b96"
     cluster="m2321.0b298c1495a26b96"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="domaiq lollipop dropped"
     md5_hashes="['44f5454193ecf4e5d7a237ddd437e0f7','726321878f23a96eec15dd1ab461a878','d7fafb8794ee2bd9d81ab897c4ad8e7d']"

   strings:
      $hex_string = { b68d16cb7b2a5865f7d3606ed8b7793b723f09e6f5d5cd5e3d14897343840824c577fae9eee561f3ecba706b5a32d2ea59a73ea5c8eb8fa3e15090e40e209bb8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
