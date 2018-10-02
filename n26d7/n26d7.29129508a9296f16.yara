
rule n26d7_29129508a9296f16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.29129508a9296f16"
     cluster="n26d7.29129508a9296f16"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious dangerousobject"
     md5_hashes="['9696068d01865d3aba9cae565b6102616b1a5ecc','a96964cec8616134e4a034a3bea4287c8bc7e117','fe55a16d4843407f05154c8d8078e02091a727ef']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.29129508a9296f16"

   strings:
      $hex_string = { d70bae9a8739be79cb9b31e16eb782efce85aa774d8e78f6252c36600a2fdc0fc40c2086d13861f902841c6fa74847f8f3740612a3ab6b094bfd9200fb671b90 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
