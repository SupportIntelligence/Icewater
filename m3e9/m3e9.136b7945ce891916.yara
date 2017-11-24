
rule m3e9_136b7945ce891916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.136b7945ce891916"
     cluster="m3e9.136b7945ce891916"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore malicious unwanted"
     md5_hashes="['20e0939060ddaaa292941502cf76b0ce','22efbb480dba6c27b2bfce2be98250cc','f5c3f62c644d7813345db98c4f669bb3']"

   strings:
      $hex_string = { 738c5609f25a3d3eb93aabba277441b8435d60bddc0a2d5baf464c7505b358fea55f654a57e6f090f4e091c52c9644e5125410ad8834a16a8a8733aa863cd447 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
