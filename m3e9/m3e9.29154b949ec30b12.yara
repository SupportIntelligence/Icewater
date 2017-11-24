
rule m3e9_29154b949ec30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29154b949ec30b12"
     cluster="m3e9.29154b949ec30b12"
     cluster_size="37"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi malicious"
     md5_hashes="['74cb87235f3b538bb89fdf1a3bae0a14','89dc862a0d585217c727726304967f37','bd6b8025e35c9c3ee37592394129a11f']"

   strings:
      $hex_string = { 2323222020161515111707021848656565654b595c7d7d7d7c7a7a777776765d5d5d34031842512b2b4a255a5e93939292919190908f8f8f8e823b0444536e2e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
