
rule k3e9_022cae1bd29b9916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.022cae1bd29b9916"
     cluster="k3e9.022cae1bd29b9916"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor berbew qukart"
     md5_hashes="['76716dbdb7afe2e2365158b2a8794baf','a7beb02fcd33852b53557a24f355b42b','efb678e7a38741699477e33c5d914592']"

   strings:
      $hex_string = { cd015365745365637572697479496e666f000000d401536574456e7472696573496e41636c41000018005f5f4765744d61696e417267730081015f736c656570 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
