
rule m3e9_21fcf24666b92bb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.21fcf24666b92bb2"
     cluster="m3e9.21fcf24666b92bb2"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ibryte optimuminstaller bundler"
     md5_hashes="['056935c342c4eae589a44b488838581b','44fcea23158ce64fbd800b1897b84ccc','ee2ff18a128f13a6a231cb5ad0ec503b']"

   strings:
      $hex_string = { 95298b7c1bdde4876a79be5e9e9d335580c2478e0fad5378bde909c93018d4ec9cbfc51a4facdb21bc405f44078d2c710d068fc2a1e7b3f1b5babe4e4842667a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
