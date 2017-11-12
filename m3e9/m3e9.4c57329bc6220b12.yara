
rule m3e9_4c57329bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4c57329bc6220b12"
     cluster="m3e9.4c57329bc6220b12"
     cluster_size="89"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0028585f28aa9249ff58226c4a53ed65','0109297c1a290e745858075c20a07e05','440124f98d1219b953ca1ff52c11e6f9']"

   strings:
      $hex_string = { 9dd7816dd7355d5d000869f8613e4094b0478d435af666963e6c8bb9bbceecfb561c7eea2f27066f03a1a38495eaaa1d0334ce2b703fb552f39ecfacafa3756c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
