
rule m3e9_16db4a94b16e52ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16db4a94b16e52ba"
     cluster="m3e9.16db4a94b16e52ba"
     cluster_size="65"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shipup ransom zbot"
     md5_hashes="['00ba7cd03eac741a164eea87d1f114ba','08f3d9883037ef04babd67d5fb399abc','94dec545e01ab863017a3b4922e9b72e']"

   strings:
      $hex_string = { 988e6723b4826b27b0865f2bacfa631fa85e5713c4525b77bf564f7bbb4a536fb7ee4783d3e24b87cfe63f8bcbda437fc7fe3773e3f23b97dff62f9bdbea338f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
