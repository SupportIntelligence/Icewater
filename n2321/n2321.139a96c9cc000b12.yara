
rule n2321_139a96c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.139a96c9cc000b12"
     cluster="n2321.139a96c9cc000b12"
     cluster_size="97"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="crypt cuegoe trojandropper"
     md5_hashes="['03f3e1e00cc29cb61bbb27e6a4230483','06f6c861f8cc8ab4ce7ccd4a9120b848','2dcca932f6907dd6459adf10e0ac207c']"

   strings:
      $hex_string = { f37a9ef90751d6f1221229d18defb34d2a11b57099a032e653517665c3c789770bddb45a3d62e50392963ee3e7183b2e38b21d1c10da16b6678c1ad50064fc58 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
