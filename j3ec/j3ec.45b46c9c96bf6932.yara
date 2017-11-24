
rule j3ec_45b46c9c96bf6932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ec.45b46c9c96bf6932"
     cluster="j3ec.45b46c9c96bf6932"
     cluster_size="424"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector aydm malicious"
     md5_hashes="['00505eaa0282caff667143e0226a701f','00818fdfc7cce56a998a83f6ec53ef86','0ac12562ab1500d1d9ef68aae92bb28f']"

   strings:
      $hex_string = { ffbb0600000031d2f7f383fa0477208db5fcfdffff31c0ac85d2740501c64aebf689f35e87f35f89c1f3a487f3eb025e5f594985c97402eb838b455029c7c38d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
