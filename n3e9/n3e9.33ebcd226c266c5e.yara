
rule n3e9_33ebcd226c266c5e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.33ebcd226c266c5e"
     cluster="n3e9.33ebcd226c266c5e"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious susp"
     md5_hashes="['663de98773803fc64bc7573b521eb217','675fe5a505b2efdc2bd956c2635e4bc6','ad04b7f9416dc3b2ffcbaa0c44175f13']"

   strings:
      $hex_string = { da035006600651059004700680069006d0056402a00651059004b006c006d006d004e006a006510590042006f0064006d005640200071007f002200730074007 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
