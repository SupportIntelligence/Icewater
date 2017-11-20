
rule k3e9_6ab2c252d88ad111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6ab2c252d88ad111"
     cluster="k3e9.6ab2c252d88ad111"
     cluster_size="766"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jykg heuristic hfsadware"
     md5_hashes="['00554d3d6aeac8cf56a3a5614f376642','00a89afdd7f02ab43109f4508f71b6b2','07506e0e1b964327b5027bef92ddfa8d']"

   strings:
      $hex_string = { d61335e8809a29f32ef7cc3b9ccd1de7d3fc2d5daa9b01632d7b620ff27d9def627fece1a60b405275b031328cd4543926b8493d4ba3eb6c588296d1a7d0cebb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
