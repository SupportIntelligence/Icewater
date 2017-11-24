
rule m2321_3b954eb9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3b954eb9c9800b16"
     cluster="m2321.3b954eb9c9800b16"
     cluster_size="142"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['003c23ea3d1ce87df9153e5b8bd14b84','038ba39bc412100753fe97d8c32b4dc8','20d50eaa0e71d397606f018b7011dd04']"

   strings:
      $hex_string = { aa254be10b0d67cf5eb97cf9f7df7fd7f2a45c799ebfffded2dcf4c18e1d6b56ad9a969b3b28265a15120cb6e8a804a1f754ca44c4618fd010081a953e6c4e75 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
