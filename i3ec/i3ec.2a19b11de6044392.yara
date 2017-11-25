
rule i3ec_2a19b11de6044392
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ec.2a19b11de6044392"
     cluster="i3ec.2a19b11de6044392"
     cluster_size="290"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector infector malicious"
     md5_hashes="['00aa3e730899cb124880992b8921ab8f','013c0b7139f5e07314db453a036eabd5','084cc0236041cc7dabc7b04086bdeb59']"

   strings:
      $hex_string = { 0600000031d2f7f383fa0477208db5fcfdffff31c0ac85d2740501c64aebf689f35e87f35f89c1f3a487f3eb025e5f594985c97402eb838b455029c7c38d8521 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
