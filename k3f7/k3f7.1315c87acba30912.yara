
rule k3f7_1315c87acba30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.1315c87acba30912"
     cluster="k3f7.1315c87acba30912"
     cluster_size="8"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['076d4cee39c0e9349be96451802a67f7','0c804281bd620c489e22321d2f6bc1d7','ccdf5e0c1996600cdd0b4624cce4402f']"

   strings:
      $hex_string = { 6372697074223e0a2f2a203c215b43444154415b202a2f0a0976617220736861646f77626f785f636f6e66203d207b0a0909616e696d6174653a20747275652c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
