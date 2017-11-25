
rule m3e9_6116e4e6ddbb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6116e4e6ddbb0912"
     cluster="m3e9.6116e4e6ddbb0912"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack malicious"
     md5_hashes="['0b7203b488d73bfb597ac4a11f82a14e','b113d542627716dc2dcfc49f5181c2e6','da20c0ed2f9ce3f68b87bc0bd4abf47d']"

   strings:
      $hex_string = { 70e58d414da86cd51fee5718b788db136bb58c30d6464b80657495e44475ab319e2af3b051724cc93aac6940b2c34af19366995c075e7610e11e977327da6747 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
