
rule m3e9_3161396b1b434912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3161396b1b434912"
     cluster="m3e9.3161396b1b434912"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod jadtre viking"
     md5_hashes="['26c812b3e70e735fe91a02af01e94858','3e6ac774b47ce4b69082fd5d9e358b40','d544f9fb4e0411ed82186b712ef0bb1a']"

   strings:
      $hex_string = { d2923dfad6975eebb5a7b1f074b6f1fd54b2f9ff479bedff3a85e9ff316be4ff2956d8ff2d4fc6f8727dadaeecd3b776d1995cffce944effca8e3efec89035f3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
