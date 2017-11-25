
rule m3e9_35abd2cf1ed31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.35abd2cf1ed31932"
     cluster="m3e9.35abd2cf1ed31932"
     cluster_size="152"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys kryptik trojandropper"
     md5_hashes="['000dedaadef15c4f41a220de2449ac1d','00e3af10bc13c2a56d95ec90f7c4f82b','26827b7cf7bca8adf01b162f49245d12']"

   strings:
      $hex_string = { 0f791fad1a4da00d940cf856e15c99dc6773d47510b3e20eefcfa6b6d7b7bdd6d542275a025eb8584a186ffcd8d349cb209ff7a7480b7e6d8f3fdb88744e4f95 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
