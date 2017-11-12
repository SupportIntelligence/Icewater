
rule n3e9_2d911e4edee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2d911e4edee30932"
     cluster="n3e9.2d911e4edee30932"
     cluster_size="46"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['0ec5201e7b4e1398f51cb538849d80e6','15c57cec7b129f47d1daf03355b71d00','63991196570d05d4cf569d48f7bbad87']"

   strings:
      $hex_string = { 339633a333a833b533ba33c733cc33d933de33eb33f033fd3302340f341434213426343334383445344a3457345c3469346e347b3480348d3492349f34a434b1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
