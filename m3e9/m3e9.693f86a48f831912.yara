
rule m3e9_693f86a48f831912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f86a48f831912"
     cluster="m3e9.693f86a48f831912"
     cluster_size="286"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['008161599d0a8f151c31445bf6ae6b0d','011c9e6d675b6ef0b65389a07d43e9f7','58a0915afd559bf6772c5ec93b7acf49']"

   strings:
      $hex_string = { 0745e8910633b3d6d1720ec9be74bb652deb8794fcb755dd387dc60dfa962ab4b1845a504abdcc05a7f8ad243e21b32099a26a136c95ffee29ea3d281d7aa32c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
