
rule k3e9_2b1df3e9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b1df3e9c8000912"
     cluster="k3e9.2b1df3e9c8000912"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor simbot"
     md5_hashes="['06e3baaee0eca2e372afa080168bcfb4','118eb0110a3c8b18475b7e6647178b3d','d77dc727b963a9ccd7aa575dca3103d7']"

   strings:
      $hex_string = { 47018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840008bfff7d9ff248de06740 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
