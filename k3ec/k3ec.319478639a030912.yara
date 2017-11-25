
rule k3ec_319478639a030912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.319478639a030912"
     cluster="k3ec.319478639a030912"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious adwareinstcap engine"
     md5_hashes="['6b5d041c98fdaa629290cca2c5d8d570','833da3f3ac1029d551751654402668e3','e4962a4c86d578c2de4098cdc86c3e6c']"

   strings:
      $hex_string = { 707269617465206269746d61736b2e2020466f72206578616d706c653a20200a0d09636861722063203d20286920262030784646293b0a0d4368616e67696e67 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
