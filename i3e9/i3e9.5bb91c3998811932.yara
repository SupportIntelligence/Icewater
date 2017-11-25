
rule i3e9_5bb91c3998811932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3e9.5bb91c3998811932"
     cluster="i3e9.5bb91c3998811932"
     cluster_size="82727"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke razy backdoor"
     md5_hashes="['00012978bd7350d3348eaee157519f7b','0003087a16dcd93b55fd9867fece6806','0016f3268d62f6cb06cc1ac25a0ea40f']"

   strings:
      $hex_string = { 85c0740533c05d59c38b54240456526a40ff15182040008bf085f674148b0f8d44240850566a006a005351ffd585c074065e33c05d59c38b54241089325eb801 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
