
rule k3e9_073cae1992939932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.073cae1992939932"
     cluster="k3e9.073cae1992939932"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="genpack qukart backdoor"
     md5_hashes="['07ac391eefa11ef7fa6e93e86d3e666f','1502dae0cbf3050f0ca93629af1d46c6','eb157204a9e1edd61b39cb133c08dd67']"

   strings:
      $hex_string = { cd015365745365637572697479496e666f000000d401536574456e7472696573496e41636c41000018005f5f4765744d61696e417267730081015f736c656570 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
